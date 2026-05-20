"""
Convert SVG to PNG using librsvg + cairo via ctypes.
Pure Python, no external Python packages needed.
Uses system libraries: librsvg-2.so.2 + libcairo.so.2
"""
import ctypes
import ctypes.util
import os
import glob

# === Cairo constants ===
CAIRO_FORMAT_ARGB32 = 0
CAIRO_STATUS_SUCCESS = 0

# === Load libraries ===
rsvg = ctypes.CDLL(ctypes.util.find_library('rsvg-2'))
cairo = ctypes.CDLL(ctypes.util.find_library('cairo'))

# === Cairo function signatures ===
cairo.cairo_image_surface_create.argtypes = [ctypes.c_int, ctypes.c_int, ctypes.c_int]
cairo.cairo_image_surface_create.restype = ctypes.c_void_p

cairo.cairo_create.argtypes = [ctypes.c_void_p]
cairo.cairo_create.restype = ctypes.c_void_p

cairo.cairo_surface_write_to_png.argtypes = [ctypes.c_void_p, ctypes.c_char_p]
cairo.cairo_surface_write_to_png.restype = ctypes.c_int

cairo.cairo_destroy.argtypes = [ctypes.c_void_p]
cairo.cairo_surface_destroy.argtypes = [ctypes.c_void_p]

cairo.cairo_scale.argtypes = [ctypes.c_void_p, ctypes.c_double, ctypes.c_double]

# === librsvg function signatures ===
# rsvg_handle_new_from_file(filename: str, error: GError**) -> RsvgHandle*
rsvg.rsvg_handle_new_from_file.argtypes = [ctypes.c_char_p, ctypes.c_void_p]
rsvg.rsvg_handle_new_from_file.restype = ctypes.c_void_p

# rsvg_handle_render_cairo(handle, cr) -> gboolean
# (newer versions also take GError**, but classic API doesn't)
rsvg.rsvg_handle_render_cairo.argtypes = [ctypes.c_void_p, ctypes.c_void_p]
rsvg.rsvg_handle_render_cairo.restype = ctypes.c_int

# rsvg does not require error param for get_intrinsic_size
# rsvg_handle_get_intrinsic_size_in_pixels(handle, out_width, out_height)
rsvg.rsvg_handle_get_intrinsic_size_in_pixels.argtypes = [
    ctypes.c_void_p,
    ctypes.POINTER(ctypes.c_double),
    ctypes.POINTER(ctypes.c_double),
]
rsvg.rsvg_handle_get_intrinsic_size_in_pixels.restype = ctypes.c_int

# rsvg_handle_close(handle, error) -> gboolean
rsvg.rsvg_handle_close.argtypes = [ctypes.c_void_p, ctypes.c_void_p]
rsvg.rsvg_handle_close.restype = ctypes.c_int

# g_object_unref(handle)
# Use rsvg_handle_close + g_object_unref from glib
gobject = ctypes.CDLL(ctypes.util.find_library('gobject-2.0'))
gobject.g_object_unref.argtypes = [ctypes.c_void_p]


def svg_to_png(svg_path, png_path, scale=2.0):
    """Convert an SVG file to PNG."""
    svg_path_b = svg_path.encode('utf-8')
    png_path_b = png_path.encode('utf-8')

    # Read SVG data and use rsvg_handle_new_from_data
    with open(svg_path, 'rb') as f:
        svg_data = f.read()

    # rsvg_handle_new_from_data(data: bytes, data_len: int, error: GError**) -> RsvgHandle*
    rsvg.rsvg_handle_new_from_data.argtypes = [ctypes.c_char_p, ctypes.c_size_t, ctypes.c_void_p]
    rsvg.rsvg_handle_new_from_data.restype = ctypes.c_void_p

    handle = rsvg.rsvg_handle_new_from_data(svg_data, len(svg_data), None)
    if not handle:
        raise RuntimeError(f"Failed to load SVG: {svg_path}")

    # Close the handle (process the SVG)
    rsvg.rsvg_handle_close(handle, None)

    # Get intrinsic size
    out_w = ctypes.c_double()
    out_h = ctypes.c_double()
    rsvg.rsvg_handle_get_intrinsic_size_in_pixels(
        handle, ctypes.byref(out_w), ctypes.byref(out_h)
    )

    width = int(out_w.value)
    height = int(out_h.value)

    if width == 0 or height == 0:
        raise RuntimeError(f"SVG has zero dimensions: {svg_path}")

    # Create cairo surface and context
    surface = cairo.cairo_image_surface_create(
        CAIRO_FORMAT_ARGB32,
        int(width * scale),
        int(height * scale),
    )
    cr = cairo.cairo_create(surface)

    # Scale up for better quality
    cairo.cairo_scale(cr, scale, scale)

    # Render SVG to cairo context
    result = rsvg.rsvg_handle_render_cairo(handle, cr)
    if not result:
        print(f"  Warning: rsvg_handle_render_cairo returned {result}")

    # Write PNG
    status = cairo.cairo_surface_write_to_png(surface, png_path_b)
    if status != CAIRO_STATUS_SUCCESS:
        raise RuntimeError(f"Failed to write PNG: {png_path} (status={status})")

    # Cleanup
    cairo.cairo_destroy(cr)
    cairo.cairo_surface_destroy(surface)
    gobject.g_object_unref(handle)

    return width, height


def main():
    img_dir = os.path.join(os.path.dirname(__file__), 'images')
    svg_files = sorted(glob.glob(os.path.join(img_dir, '*.svg')))

    if not svg_files:
        print("No SVG files found!")
        return

    print(f"Converting {len(svg_files)} SVGs to PNG (2x resolution)...")
    for svg_path in svg_files:
        name = os.path.splitext(os.path.basename(svg_path))[0]
        png_path = os.path.join(img_dir, f"{name}.png")
        try:
            w, h = svg_to_png(svg_path, png_path, scale=2.0)
            size_kb = os.path.getsize(png_path) / 1024
            print(f"  {name}.png ({w}x{h} @2x -> {w*2}x{h*2}, {size_kb:.0f} KB)")
        except Exception as e:
            print(f"  {name}.png FAILED: {e}")

    print("Done!")


if __name__ == '__main__':
    main()
